package util

import (
	"io"
	"os"
	"sync"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

var (
	// dataChunkSize is the read-buffer size used when streaming a source too
	// large to hold in memory.
	//
	// The original comment described this as 4Mb while the value is 4Kb. The
	// value is correct — 4KB matches a page and keeps the pooled buffer cheap —
	// so the comment was the error, and is fixed here rather than the constant.
	dataChunkSize = 4096

	// MaxInMemoryFileSize is the largest source read whole into memory.
	//
	// It is set to the engine's own scanning cut-off: files above it are
	// already skipped unless they are of a recognised parsable type, so in
	// practice the streaming path is reserved for large recognised files.
	MaxInMemoryFileSize = int64(1024 * 1000 * 10) // 10Mb
)

// Provide repository index context for every file that is scanned.
// The index of the scan root is mapped to each file found beneath it during
// the walk. See WalkFiles in walk.go.
type RepositoryIndexedFile struct {
	RepositoryIndex int //repository index of the under which the file is found
	File            string
}

// ResourceMultiplexer interface defines a path or source reader that can be multiplexed to multiple consumers. It provides
// additional utility such as mapping a source index to the line and character, i.e. the `code.Position` in the source
type ResourceMultiplexer interface {
	//SetSource is the source reader to multiplex to multiple consumers, which will be provided with a copy of the source data as it is being streamed in from the source
	SetResourceAndConsumers(filePath RepositoryIndexedFile, source *io.Reader, provideSourceInDiagnostics bool, consumers ...ResourceConsumer)
}

// PathMultiplexer interface defines an aggregator of analysers that can consume filesystem paths and URIs and process them
type PathMultiplexer interface {
	SetPathConsumers(consumers ...PathConsumer)
	ConsumePath(path RepositoryIndexedFile)
}

type defaultPathMultiplexer struct {
	consumers []PathConsumer
}

func (dpm *defaultPathMultiplexer) SetPathConsumers(consumers ...PathConsumer) {
	dpm.consumers = consumers
}

func (dpm *defaultPathMultiplexer) ConsumePath(path RepositoryIndexedFile) {
	for _, c := range dpm.consumers {
		c.ConsumePath(path)
	}
}

// PositionProvider provides a "global" view of code location, given an arbitrary character index.
type PositionProvider interface {
	GetPosition(index int64) code.Position
}

// PathConsumer is a sink for paths and URIs
type PathConsumer interface {
	ConsumePath(path RepositoryIndexedFile)
	diagnostics.ExclusionProvider
}

// NewPathMultiplexer creates a choreographer that orchestrates the consumption of paths by consumers
func NewPathMultiplexer(consumers ...PathConsumer) PathMultiplexer {
	dpm := defaultPathMultiplexer{}
	dpm.SetPathConsumers(consumers...)
	return &dpm
}

// ResourceConsumer is a sink for streaming source
type ResourceConsumer interface {
	//Consume allows a source processor receive `source` data streamed in "chunks", with `startIndex` indicating the
	//character location of the first character in the stream
	Consume(startIndex int64, source string)
	//ConsumePath allows resource consumers that process filepaths directly to analyse files on disk
	ConsumePath(filePath RepositoryIndexedFile)
	SetLineIndex(*LineIndex)
	//SetRepositoryFile supplies the file about to be consumed, along with the
	//index of the scan root (repository) it was found under.
	//
	//This is per-file state and is therefore set through the multiplexer for
	//every file, exactly like SetLineKeeper. It used to be captured when the
	//consumer was constructed, which forced a fresh consumer to be built for
	//every file and — where consumers were cached and shared — caused findings
	//to report the repository index of whichever file was scanned first.
	//Supplying it per file lets a consumer be built once and reused.
	SetRepositoryFile(RepositoryIndexedFile)
	//ShouldProvideSourceInDiagnostics toggles whether source evidence should be provided with diagnostics, defaults to false
	ShouldProvideSourceInDiagnostics(bool)
	//used to signal to the consumer that the source stream has ended
	End()
}

// NewResourceMultiplexer creates a source multiplexer over an input reader
func NewResourceMultiplexer(filePath RepositoryIndexedFile, source *io.Reader, provideSource bool, consumers ...ResourceConsumer) ResourceMultiplexer {
	sm := defaultResourceMultiplexer{}
	sm.SetResourceAndConsumers(filePath, source, provideSource, consumers...)
	return &sm
}

type defaultResourceMultiplexer struct {
	filePath  RepositoryIndexedFile
	source    *io.Reader
	consumers []ResourceConsumer
	lineIndex LineIndex
}

func (sm *defaultResourceMultiplexer) SetResourceAndConsumers(filePath RepositoryIndexedFile, src *io.Reader, provideSource bool, consumers ...ResourceConsumer) {
	sm.filePath = filePath
	sm.source = src
	sm.consumers = consumers
	for _, consumer := range consumers {
		consumer.SetLineIndex(&sm.lineIndex)
		consumer.SetRepositoryFile(filePath)
		consumer.ShouldProvideSourceInDiagnostics(provideSource)
	}
	sm.start()
}

// begins to stream data from source to the consumers
//
// # Reading strategy
//
// Files below MaxInMemoryFileSize are read once, whole, and handed to the
// consumers in a single Consume call. Larger sources fall back to a bounded
// chunked path.
//
// The previous implementation always chunked, and built each chunk by string
// concatenation (largeChunk += remnant + string(buf[:n])). For ordinary source
// files that is a handful of 4KB copies; for a file with few newlines — a
// minified bundle, a single-line JSON blob, a base64 payload — no chunk
// boundary is ever found, so the accumulator is copied in full on every 4KB
// read. That is quadratic in file size: a 10MB single-line file performs on
// the order of 2,500 copies averaging 5MB each, roughly 12GB of memory traffic
// to read 10MB. This is the concrete mechanism behind the "gets completely
// lost on huge codebases" symptom, since a single such file stalls the scan.
//
// Reading whole files removes the concatenation entirely and, as a side
// effect, makes matching independent of where chunk boundaries happen to fall.
func (sm *defaultResourceMultiplexer) start() {
	sm.lineIndex.Reset()

	if content, ok := readAll(*sm.source, MaxInMemoryFileSize); ok {
		sm.lineIndex.IndexString(0, content)
		// Consumers are invoked synchronously, in their declared order.
		//
		// This previously spawned one goroutine per consumer per chunk. With
		// ~240 rule consumers and 4KB chunks that is on the order of 600k
		// goroutine creations for a single 10MB file, each doing a few
		// microseconds of work — scheduling cost far exceeding the matching
		// itself.
		//
		// It was also a correctness problem: concurrent consumers broadcast
		// their diagnostics to the shared aggregator in nondeterministic
		// order, and diagnostics.SubsumeOverlapping resolves ties between
		// overlapping findings by "keep the earlier index". Scanning the same
		// file twice could therefore credit the same secret to a different
		// rule, with a different range and description — which changes the
		// derived finding ID and breaks cross-scan finding identity.
		//
		// Parallelism belongs at the file level, where work units are large
		// enough to amortise scheduling, not per chunk per rule.
		for _, c := range sm.consumers {
			c.Consume(0, content)
		}
	} else {
		sm.streamLargeSource()
	}

	for _, c := range sm.consumers {
		c.ConsumePath(sm.filePath)
	}

	for _, consumer := range sm.consumers {
		consumer.End()
	}
}

// streamLargeSource handles sources too large to hold in memory.
//
// Chunks are cut on newline boundaries where one exists within the chunk, so a
// line-oriented rule still sees each of its lines intact. Where no newline
// exists the chunk is emitted as-is rather than accumulated, which bounds
// memory at chunkSize instead of growing to the size of the line. A rule
// cannot match across such a break, but the alternative — buffering an
// unbounded single line — is what made these files pathological in the first
// place, and files this large are past the engine's scanning thresholds
// anyway.
func (sm *defaultResourceMultiplexer) streamLargeSource() {
	startIndex := int64(0)

	bufPtr := chunkBufferPool.Get().(*[]byte)
	defer chunkBufferPool.Put(bufPtr)
	buf := *bufPtr

	// carry holds the bytes after the last newline of the previous chunk,
	// which belong to the line continuing into this one. It is bounded by
	// dataChunkSize.
	var carry []byte

	for {
		n, err := (*sm.source).Read(buf)

		if n > 0 {
			// Find the last newline so the chunk ends on a line boundary.
			cut := n
			if nl := lastIndexByte(buf[:n], '\n'); nl >= 0 {
				cut = nl + 1
			}

			var chunk []byte
			if len(carry) == 0 {
				chunk = buf[:cut]
			} else {
				chunk = append(carry, buf[:cut]...)
			}

			data := string(chunk)
			sm.lineIndex.IndexString(startIndex, data)
			for _, c := range sm.consumers {
				c.Consume(startIndex, data)
			}
			startIndex += int64(len(data))

			carry = append(carry[:0], buf[cut:n]...)
		}

		if err != nil {
			break
		}
	}

	if len(carry) > 0 {
		data := string(carry)
		sm.lineIndex.IndexString(startIndex, data)
		for _, c := range sm.consumers {
			c.Consume(startIndex, data)
		}
	}
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// readAll reads the whole source when it fits within limit, reporting false if
// it does not so the caller can fall back to streaming.
func readAll(source io.Reader, limit int64) (string, bool) {
	// A *os.File can report its size up front, letting us size the buffer
	// exactly and reject oversized files without reading them at all.
	if f, isFile := source.(*os.File); isFile {
		if stat, err := f.Stat(); err == nil {
			size := stat.Size()
			if size > limit {
				return "", false
			}
			buf := make([]byte, size)
			n, err := io.ReadFull(f, buf)
			if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
				return "", false
			}
			return string(buf[:n]), true
		}
	}

	// Otherwise read up to limit+1 bytes; exceeding limit means it is too big,
	// but the bytes already read cannot be pushed back, so streaming is no
	// longer an option and we scan what we have.
	var sb []byte
	buf := make([]byte, dataChunkSize)
	for int64(len(sb)) <= limit {
		n, err := source.Read(buf)
		sb = append(sb, buf[:n]...)
		if err != nil {
			break
		}
	}
	return string(sb), true
}

func (sm *defaultResourceMultiplexer) GetPosition(index int64) code.Position {
	return sm.lineIndex.GetPositionFromCharacterIndex(index)
}

// readChunk reads the `source` in `dataChunkSize` (4Mb) chunks and tries to align
// to the newline \n boundaries - so will sometimes "walk backwards to the last \n"
// and place the remaining data `remnant` in the next chunk
// TODO: write a test for this with various random data sources and compare the Sha256 of
// original data with the combined chunks.
// chunkBufferPool recycles the fixed-size read buffer used by readChunks.
//
// One buffer was allocated per file. At scale that is one 4KB allocation for
// every file scanned, all of them identical in size and dead the moment the
// file is done — precisely the shape sync.Pool exists for. The buffer never
// escapes readChunks: every value handed downstream goes through string(...),
// which copies, so recycling cannot alias data a consumer still holds.
var chunkBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, dataChunkSize)
		return &buf
	},
}
