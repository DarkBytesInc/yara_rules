rule Win_Worm_Stration_328
{
strings:
	$a0 = { e8753436ce63623e0e3ac6f457ed686876fe6d6860d15aff099ea563e668e2cc464b545a4ae0d90e2f3f2da77102aeaaf60bb623a008b59847b4b2495ef70fff7a5fcef04f0f03b38ce776d79720a1d198ed5ece92bc5ce4bbdc98628f705f6a4522385aaf835ab812ce495c3ff1d486 }

condition:
	$a0
}

        