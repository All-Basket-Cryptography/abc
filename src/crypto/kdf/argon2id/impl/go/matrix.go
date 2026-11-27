package abcargon2id

import "encoding/binary"

func initialize(memory []Block, p Parameters, h0 *[64]byte) {
	var seed [72]byte
	copy(seed[:], h0[:])
	for lane := 0; lane < p.lanes; lane++ {
		binary.LittleEndian.PutUint32(seed[68:], uint32(lane))
		for index := 0; index < 2; index++ {
			binary.LittleEndian.PutUint32(seed[64:], uint32(index))
			var encoded [BlockSize]byte
			longHash(seed[:], encoded[:])
			block := &memory[lane*p.laneBlocks()+index]
			for i := range block {
				block[i] = binary.LittleEndian.Uint64(encoded[8*i:])
			}
		}
	}
}

func fillPass(memory []Block, p Parameters, pass uint32) {
	for slice := 0; slice < slices; slice++ {
		// Other lanes cannot reference this slice until its barrier.
		for lane := 0; lane < p.lanes; lane++ {
			fillSegment(memory, p, pass, slice, lane)
		}
	}
}

func fillSegment(memory []Block, p Parameters, pass uint32, slice, lane int) {
	first := 0
	if pass == 0 && slice == 0 {
		first = 2
	}
	independent := pass == 0 && slice < 2
	addresses := addressBlock{input: Block{
		uint64(pass), uint64(lane), uint64(slice), uint64(p.blockCount), uint64(p.passes), variant,
	}}
	laneBlocks := p.laneBlocks()
	base := lane * laneBlocks
	for i := first; i < p.segment; i++ {
		column := slice*p.segment + i
		previous := column - 1
		if column == 0 {
			previous = laneBlocks - 1
		}
		before := &memory[base+previous]
		pseudo := before[0]
		if independent {
			pseudo = addresses.word(i, first)
		}
		referenceLane := lane
		if pass != 0 || slice != 0 {
			referenceLane = int((pseudo >> 32) % uint64(p.lanes))
		}
		index := referenceColumn(p, pass, slice, i, referenceLane == lane, uint32(pseudo))
		reference := &memory[referenceLane*laneBlocks+index]
		next := compress(before, reference)
		destination := &memory[base+column]
		if pass == 0 {
			*destination = next
		} else {
			for j := range destination {
				destination[j] ^= next[j]
			}
		}
	}
}

func referenceColumn(p Parameters, pass uint32, slice, index int, sameLane bool, j1 uint32) int {
	laneBlocks := p.laneBlocks()
	finished := slice * p.segment
	if pass != 0 {
		finished = laneBlocks - p.segment
	}
	area := finished
	if sameLane {
		area += index - 1
	} else if index == 0 {
		area--
	}
	// The reference area fits in 32 bits, as do both factors.
	value := uint64(j1)
	squared := (value * value) >> 32
	relative := area - 1 - int((uint64(area)*squared)>>32)
	start := 0
	if pass != 0 && slice != slices-1 {
		start = (slice + 1) * p.segment
	}
	return (start + relative) % laneBlocks
}

type addressBlock struct {
	input, output Block
}

func (a *addressBlock) word(index, first int) uint64 {
	if index == first || index%words == 0 {
		var zero Block
		a.input[6]++
		intermediate := compress(&zero, &a.input)
		a.output = compress(&zero, &intermediate)
	}
	return a.output[index%words]
}
