package target

// Permutation is a stateless bijection over [0, total): given each scan
// position in turn, it yields a pseudo-random target index without storing any
// list. It is a balanced Feistel network (always invertible, for any round
// function) sized to the smallest even power-of-two domain >= total, with
// cycle-walking to fold that domain down to exactly [0, total). This is the
// technique masscan/ZMap use to randomize internet-wide scan order.
type Permutation struct {
	total  uint64
	half   uint   // bits per Feistel half; domain is 2^(2*half)
	mask   uint64 // (1 << half) - 1
	key    uint64
	rounds int
}

// NewPermutation builds a permutation over [0, total) keyed by seed.
func NewPermutation(total, seed uint64) *Permutation {
	if total == 0 {
		total = 1
	}
	// Size the Feistel domain to the smallest even bit-width whose 2^bits is at
	// least total (and at least 2 bits). total itself stays the cycle-walk bound
	// so Shuffle only ever returns indices in [0, total).
	size := total
	if size < 2 {
		size = 2
	}
	bits := uint(1)
	for (uint64(1) << bits) < size {
		bits++
	}
	if bits%2 != 0 {
		bits++ // Feistel needs an even split
	}
	return &Permutation{
		total:  total,
		half:   bits / 2,
		mask:   (uint64(1) << (bits / 2)) - 1,
		key:    seed,
		rounds: 4,
	}
}

// splitmix64: a fast, well-mixed round function.
func mix(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// encrypt applies the Feistel network; it is a bijection over the full
// 2^(2*half) domain.
func (p *Permutation) encrypt(x uint64) uint64 {
	l := (x >> p.half) & p.mask
	r := x & p.mask
	for i := 0; i < p.rounds; i++ {
		f := mix(r^p.key^uint64(i)*0x9e3779b1) & p.mask
		l, r = r, l^f
	}
	return (l << p.half) | r
}

// Shuffle maps a scan position in [0, total) to a distinct target index in
// [0, total). Cycle-walking guarantees the result stays in range while
// preserving the bijection.
func (p *Permutation) Shuffle(pos uint64) uint64 {
	x := p.encrypt(pos)
	for x >= p.total {
		x = p.encrypt(x)
	}
	return x
}
