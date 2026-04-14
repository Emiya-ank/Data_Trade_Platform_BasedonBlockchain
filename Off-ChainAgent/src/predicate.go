package offchain

import "github.com/consensys/gnark/frontend"

// 范围谓词约束电路：证明 Plaintext[TargetIdx] ∈ [RangeMin, RangeMax]
type RangeConstrainCircuit struct {
	// 私有输入
	Plaintext  [MAX_N]frontend.Variable // 明文数据
	TextLen    frontend.Variable        // 明文长度
	Randomness frontend.Variable        // Pedersen 承诺随机数

	// 公开输入
	Commit_x frontend.Variable `gnark:",public"` // 承诺值
	Index    frontend.Variable `gnark:",public"` // 目标索引
	RangeMin frontend.Variable `gnark:",public"` // 范围最小值
	RangeMax frontend.Variable `gnark:",public"` // 范围最大值
}

func (c *RangeConstrainCircuit) Define(api frontend.API) error {
	// 约束1：索引在数据范围内
	api.AssertIsLessOrEqual(c.Index, c.TextLen)

	// 约束2：RangeMin ≤ RangeMax
	api.AssertIsLessOrEqual(c.RangeMin, c.RangeMax)

	// 约束3：Plaintext[TargetIdx] ∈ [RangeMin, RangeMax]
	selectors := make([]frontend.Variable, MAX_N)

	sum := frontend.Variable(0)

	for i := 0; i < MAX_N; i++ {
		si := api.IsZero(api.Sub(c.Index, i))
		selectors[i] = si
		sum = api.Add(sum, si)
	}
	api.AssertIsEqual(sum, 1)

	x := frontend.Variable(0)
	for i := 0; i < MAX_N; i++ {
		x = api.Add(x, api.Mul(selectors[i], c.Plaintext[i]))
	}
	api.AssertIsLessOrEqual(c.RangeMin, x)
	api.AssertIsLessOrEqual(x, c.RangeMax)

	// 约束4：Pedersen 承诺验证
	sum = frontend.Variable(0)
	generators := PedersenGenerators()
	for i := 0; i < MAX_N; i++ {
		cmp := api.Cmp(c.TextLen, i+1)
		isGt := api.IsZero(api.Sub(cmp, 1))
		isEq := api.IsZero(cmp)
		si := api.Add(isGt, isEq)
		term := api.Mul(c.Plaintext[i], generators[i])
		term = api.Mul(term, si)
		sum = api.Add(sum, term)
	}

	H := generators[MAX_N]
	randomTerm := api.Mul(c.Randomness, H)
	sum = api.Add(sum, randomTerm)
	api.AssertIsEqual(c.Commit_x, sum)
	return nil
}

// 选择性披露谓词电路约束
type SelectiveDisclosureCircuit struct {
	// 私有输入
	Plaintext  [MAX_N]frontend.Variable	// 明文数据
	Mask       [MAX_N]frontend.Variable	// 披露掩码，1 表示披露，0 表示隐藏
	TextLen    frontend.Variable		// 明文长度
	Randomness frontend.Variable		// Pedersen 承诺随机数

	// 公开输入
	DisclosedLen    frontend.Variable        `gnark:",public"`	// 披露数据长度
	DisclosedValues [MAX_N]frontend.Variable `gnark:",public"`	// 披露数据值
	Commit_x        frontend.Variable        `gnark:",public"`	// 承诺值
	Commit_x_subset frontend.Variable        `gnark:",public"`	// 披露数据的承诺值
}

func (c *SelectiveDisclosureCircuit) Define(api frontend.API) error {
	// 约束1：掩码布尔性
	for i := 0; i < MAX_N; i++ {
		api.AssertIsBoolean(c.Mask[i])
	}

	// 约束2：披露数据一致性
	xPrime := make([]frontend.Variable, MAX_N)
	for i := 0; i < MAX_N; i++ {
		xPrime[i] = api.Mul(c.Mask[i], c.Plaintext[i])
		api.AssertIsEqual(c.DisclosedValues[i], xPrime[i])
	}

	// 约束3：Pedersen 承诺验证
	sum := frontend.Variable(0)
	generators := PedersenGenerators()
	for i := 0; i < MAX_N; i++ {
		cmp := api.Cmp(c.TextLen, i+1)
		isGt := api.IsZero(api.Sub(cmp, 1))
		isEq := api.IsZero(cmp)
		si := api.Add(isGt, isEq)
		term := api.Mul(c.Plaintext[i], generators[i])
		term = api.Mul(term, si)
		sum = api.Add(sum, term)
	}

	H := generators[MAX_N]
	randomTerm := api.Mul(c.Randomness, H)
	sum = api.Add(sum, randomTerm)
	api.AssertIsEqual(c.Commit_x, sum)

	// 约束4：披露数据的 Pedersen 承诺验证
	sum = frontend.Variable(0)
	generators = PedersenGenerators()
	for i := 0; i < MAX_N; i++ {
		term := api.Mul(c.DisclosedValues[i], generators[i])
		sum = api.Add(sum, term)
	}

	H = generators[MAX_N]
	randomTerm = api.Mul(c.Randomness, H)
	sum = api.Add(sum, randomTerm)
	api.AssertIsEqual(c.Commit_x_subset, sum)
	return nil
}

// 哈希一致性谓词电路约束
type HashConsistencyCircuit struct {
	// 私有输入
	Plaintext  [MAX_N]frontend.Variable // 明文数据
	TextLen    frontend.Variable        // 明文长度
	Randomness frontend.Variable        // Pedersen 承诺随机数

	// 公开输入
	Commit_x frontend.Variable `gnark:",public"` // 承诺值
	Hash_y   frontend.Variable `gnark:",public"` // 哈希值
}

func (c *HashConsistencyCircuit) Define(api frontend.API) error {
	// TODO
	return nil
}
