package util

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/adedayo/checkmate/pkg/core/code"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

var (
	dataChunkSize = 4096 //read in source data 4k-bytes chunks
	reNL          = regexp.MustCompile(`\n`)
)

//Provide repository index context for every file that is scanned
//In FindFiles(paths []string). The index of the paths is mapped to each file found during search
type RepositoryIndexedFile struct {
	RepositoryIndex int //repository index of the under which the file is found
	File            string
}

//FindFiles recursively searches the directories and files contained in paths and returns a unique list of files
func FindFiles(paths []string) []RepositoryIndexedFile {

	// directoryOrFile := make(map[string]bool)
	// worklist := make(map[string]struct{})
	for i, p := range paths {
		path := filepath.Clean(p)
		paths[i] = path
		// if fileInfo, err := os.Stat(path); !os.IsNotExist(err) {
		// 	directoryOrFile[path] = fileInfo.IsDir()
		// }
	}

	out := []RepositoryIndexedFile{}
	for i, path := range paths {
		for _, file := range getFiles(path) {
			out = append(out, RepositoryIndexedFile{
				RepositoryIndex: i,
				File:            file,
			})
		}
	}

	// var nothing struct{}
	// //collect unique files to analyse
	// for file, isDir := range directoryOrFile {
	// 	if isDir {
	// 		for _, f := range getFiles(file) {
	// 			worklist[f] = nothing
	// 		}
	// 	} else {
	// 		worklist[file] = nothing
	// 	}
	// }

	// result := make([]string, 0, len(worklist))
	// for path := range worklist {
	// 	result = append(result, path)
	// }

	// worklist = nil

	return out
}

func getFiles(dir string) (paths []string) {
	filepath.WalkDir(dir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	return
}

//ResourceMultiplexer interface defines a path or source reader that can be multiplexed to multiple consumers. It provides
//additional utility such as mapping a source index to the line and character, i.e. the `code.Position` in the source
type ResourceMultiplexer interface {
	//SetSource is the source reader to multiplex to multiple consumers, which will be provided with a copy of the source data as it is being streamed in from the source
	SetResourceAndConsumers(filePath RepositoryIndexedFile, source *io.Reader, provideSourceInDiagnostics bool, consumers ...ResourceConsumer)
}

//PathMultiplexer interface defines an aggregator of analysers that can consume filesystem paths and URIs and process them
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

//PositionProvider provides a "global" view of code location, given an arbitrary character index.
type PositionProvider interface {
	GetPosition(index int64) code.Position
}

//PathConsumer is a sink for paths and URIs
type PathConsumer interface {
	ConsumePath(path RepositoryIndexedFile)
	diagnostics.ExclusionProvider
}

//NewPathMultiplexer creates a choreographer that orchestrates the consumption of paths by consumers
func NewPathMultiplexer(consumers ...PathConsumer) PathMultiplexer {
	dpm := defaultPathMultiplexer{}
	dpm.SetPathConsumers(consumers...)
	return &dpm
}

//ResourceConsumer is a sink for streaming source
type ResourceConsumer interface {
	//Consume allows a source processor receive `source` data streamed in "chunks", with `startIndex` indicating the
	//character location of the first character in the stream
	Consume(startIndex int64, source string)
	//ConsumePath allows resource consumers that process filepaths directly to analyse files on disk
	ConsumePath(filePath RepositoryIndexedFile)
	SetLineKeeper(*LineKeeper)
	//ShouldProvideSourceInDiagnostics toggles whether source evidence should be provided with diagnostics, defaults to false
	ShouldProvideSourceInDiagnostics(bool)
	//used to signal to the consumer that the source stream has ended
	End()
}

//NewResourceMultiplexer creates a source multiplexer over an input reader
func NewResourceMultiplexer(filePath RepositoryIndexedFile, source *io.Reader, provideSource bool, consumers ...ResourceConsumer) ResourceMultiplexer {
	sm := defaultResourceMultiplexer{}
	sm.SetResourceAndConsumers(filePath, source, provideSource, consumers...)
	return &sm
}

type defaultResourceMultiplexer struct {
	filePath   RepositoryIndexedFile
	source     *io.Reader
	consumers  []ResourceConsumer
	lineKeeper LineKeeper
}

func (sm *defaultResourceMultiplexer) SetResourceAndConsumers(filePath RepositoryIndexedFile, src *io.Reader, provideSource bool, consumers ...ResourceConsumer) {
	sm.filePath = filePath
	sm.source = src
	sm.consumers = consumers
	for _, consumer := range consumers {
		consumer.SetLineKeeper(&sm.lineKeeper)
		consumer.ShouldProvideSourceInDiagnostics(provideSource)
	}
	sm.start()
}

//begins to stream data from source to the consumers
func (sm *defaultResourceMultiplexer) start() {
	startIndex := int64(0)

	for data := range readChunks(*sm.source, dataChunkSize) {
		locations := reNL.FindAllStringIndex(data, -1)
		locs := []int{}
		for _, l := range locations {
			locs = append(locs, l[0])
		}
		sm.lineKeeper.appendEOLs(locs)
		var wg sync.WaitGroup
		consumers := sm.consumers
		wg.Add(len(consumers))
		for _, c := range consumers {
			go func(consumer ResourceConsumer, w *sync.WaitGroup) {
				defer w.Done()
				consumer.Consume(startIndex, data)
			}(c, &wg)
		}
		wg.Wait()
		startIndex += int64(len(data))
	}

	for _, c := range sm.consumers {
		c.ConsumePath(sm.filePath)
	}

	for _, consumer := range sm.consumers {
		consumer.End()
	}

}

func (sm *defaultResourceMultiplexer) GetPosition(index int64) code.Position {
	return sm.lineKeeper.GetPositionFromCharacterIndex(index)
}

//readChunk reads the `source` in `dataChunkSize` (4Mb) chunks and tries to align
//to the newline \n boundaries - so will sometimes "walk backwards to the last \n"
//and place the remaining data `remnant` in the next chunk
//TODO: write a test for this with various random data sources and compare the Sha256 of
//original data with the combined chunks.
func readChunks(source io.Reader, chunkSize int) chan string {
	out := make(chan string)
	var largeChunk, remnant string
	buf := make([]byte, chunkSize)
	go func() {
		defer close(out)
		for {
			len, err := source.Read(buf)
			if err == nil {
				//find the last newline position in the buffer
				nlFound := false
				nlLocation := -1
				for i := len - 1; i >= 0; i-- {
					if buf[i] == '\n' {
						nlFound = true
						nlLocation = i
						break
					}
				}
				if nlFound {
					out <- largeChunk + remnant + string(buf[:nlLocation+1])
					//the remaining data after newline
					remnant = string(buf[nlLocation+1 : len])
					largeChunk = ""
				} else {
					largeChunk += remnant + string(buf[:len])
					remnant = ""
				}
			} else {
				out <- largeChunk + remnant + string(buf[:len])
				break
			}
		}
	}()
	return out
}

//LineKeeper keeps track of line numberson a textual source file and can map character location to the relevant `code.Position`
type LineKeeper struct {
	EOLLocations []int // end-of-line locations
	lock         sync.Mutex
}

func (lk *LineKeeper) appendEOLs(eols []int) {
	sorted := sort.IntSlice(eols)
	lk.lock.Lock()
	//if this is not the first set of EOLs, "continue" from where we stopped last time, by adding the location to
	//these set of eol's position. Note this works because we chunk data on EOL boundaries
	if len(lk.EOLLocations) > 0 {
		last := lk.EOLLocations[len(lk.EOLLocations)-1]
		for i := range sorted {
			sorted[i] += last + 1
		}
	}
	lk.EOLLocations = append(lk.EOLLocations, sorted...)
	lk.lock.Unlock()
}

//GetPositionFromCharacterIndex returns the `code.Position` given the index of the character in the file
func (lk *LineKeeper) GetPositionFromCharacterIndex(pos int64) code.Position {
	//lk.EOLLocations are sorted
	lk.lock.Lock()
	defer lk.lock.Unlock()
	if len(lk.EOLLocations) > 0 {
		end := int64(len(lk.EOLLocations) - 1)
		if pos > int64(lk.EOLLocations[end]) {
			return code.Position{
				Line:      end + 1,
				Character: pos - int64(lk.EOLLocations[end]) - 1,
			}
		}
		for i, eol := range lk.EOLLocations {
			if int64(eol) >= pos {
				if i > 0 {
					return code.Position{
						Line:      int64(i),
						Character: pos - int64(lk.EOLLocations[i-1]) - 1,
					}
				}
				break
			}
		}
	}
	return code.Position{
		Line:      0,
		Character: pos,
	}
}
