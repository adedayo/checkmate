package util

import (
	"io"
	"regexp"
	"sort"
	"sync"

	"github.com/adedayo/checkmate/pkg/common/code"
)

var (
	dataChunkSize = 4096 //read in source data 4k-bytes chunks
	// lineKeeperKey lkKey = 0
	reNL = regexp.MustCompile(`\n`)
)

//SourceMultiplexer interface defines a source reader that can be multiplexed to multiple consumers. It provides
//additional utility such as mapping a source index to the line and character, i.e. the `code.Position` in the source
type SourceMultiplexer interface {
	//SetSource is the source reader to multiplex to multiple consumers, which will be provided with a copy of the source data as it is being streamed in from the source
	SetSourceAndConsumers(source *io.Reader, provideSourceInDiagnostics bool, consumers ...SourceConsumer)
}

//PositionProvider provides a "global" view of code location, given an arbitrary character index.
type PositionProvider interface {
	GetPosition(index int) code.Position
}

//SourceConsumer is a sink for streaming source
type SourceConsumer interface {
	//Consume allows a source processor receive `source` data streamed in "chunks", with `startIndex` indicating the
	//character location of the first character in the stream
	Consume(startIndex int, source string)
	SetLineKeeper(*LineKeeper)
	//ShouldProvideSourceInDiagnostics toggles whether source evidence should be provided with diagnostics, defaults to false
	ShouldProvideSourceInDiagnostics(bool)
	//used to signal to the consumer that the source stream has ended
	End()
}

//NewSourceMultiplexer creates a source multiplexer over an input reader
func NewSourceMultiplexer(source *io.Reader, provideSource bool, consumers ...SourceConsumer) SourceMultiplexer {
	sm := defaultSourceMultiplexer{}
	sm.SetSourceAndConsumers(source, provideSource, consumers...)
	return &sm
}

type defaultSourceMultiplexer struct {
	source     *io.Reader
	consumers  []SourceConsumer
	lineKeeper LineKeeper
}

func (sm *defaultSourceMultiplexer) SetSourceAndConsumers(src *io.Reader, provideSource bool, consumers ...SourceConsumer) {
	sm.source = src
	sm.consumers = consumers
	for _, consumer := range consumers {
		consumer.SetLineKeeper(&sm.lineKeeper)
		consumer.ShouldProvideSourceInDiagnostics(provideSource)
	}
	sm.start()
}

//begins to stream data from source to the consumers
func (sm *defaultSourceMultiplexer) start() {
	startIndex := 0

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
			go func(consumer SourceConsumer, w *sync.WaitGroup) {
				defer w.Done()
				consumer.Consume(startIndex, data)
			}(c, &wg)
		}
		wg.Wait()
		startIndex += len(data)
	}
	for _, consumer := range sm.consumers {
		consumer.End()
	}

}

func (sm *defaultSourceMultiplexer) GetPosition(index int) code.Position {
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
			sorted[i] += last
		}
	}
	lk.EOLLocations = append(lk.EOLLocations, sorted...)
	lk.lock.Unlock()
}

//GetPositionFromCharacterIndex returns the `code.Position` given the index of the character in the file
func (lk *LineKeeper) GetPositionFromCharacterIndex(pos int) code.Position {
	//lk.EOLLocations are sorted
	lk.lock.Lock()
	defer lk.lock.Unlock()
	if len(lk.EOLLocations) > 0 {
		end := len(lk.EOLLocations) - 1
		if pos > lk.EOLLocations[end] {
			return code.Position{
				Line:      end,
				Character: pos - lk.EOLLocations[end],
			}
		}
		for i, eol := range lk.EOLLocations {
			if eol > pos {
				if i > 1 {
					return code.Position{
						Line:      i - 1,
						Character: pos - lk.EOLLocations[i-1],
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
