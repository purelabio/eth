package eth

import "testing"

func BenchmarkMockAbiFunction(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Our contract is a bit small.
		_ = TestAbi.Function("one")
		_ = TestAbi.Function("two")
		_ = TestAbi.Function("three")
		_ = TestAbi.Function("four")
	}
}

func BenchmarkMockAbiEvent(b *testing.B) {
	for i := 0; i < b.N; i++ {
		// Our contract is a bit small.
		_ = TestAbi.Event("Transfer")
		_ = TestAbi.Event("Transfer")
		_ = TestAbi.Event("Transfer")
		_ = TestAbi.Event("Transfer")
	}
}

func BenchmarkMockAbiFunctionFromMap(b *testing.B) {
	funcs := map[string]AbiFunction{}
	for _, method := range TestAbi {
		switch method := method.(type) {
		case AbiFunction:
			funcs[method.Name] = method
		}
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		noopAbiFunc(funcs["one"])
		noopAbiFunc(funcs["two"])
		noopAbiFunc(funcs["three"])
		noopAbiFunc(funcs["four"])
	}
}

//go:noinline
func noopAbiFunc(AbiFunction) {}

func BenchmarkAbiEncoding(b *testing.B) {
	atype, err := ParseAbiType("uint32[2][3][4]")
	if err != nil {
		b.Fatalf("%+v", err)
	}

	var input = [4][3][2]uint32{{{1, 2}, {3, 4}, {5, 6}}, {{7, 8}, {9, 10}, {11, 12}}, {{13, 14}, {15, 16}, {17, 18}}, {{19, 20}, {21, 22}, {23, 24}}}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := AbiMarshal(atype, input)
		if err != nil {
			b.Fatalf("%+v", err)
		}
	}
}
