rule Win_Trojan_Delf_755
{
strings:
	$a0 = { 6e6a957262138585a8d2723081d7e20f1f987eea32270fd39ddb4cdef47b46885ecdf7e74eaa82925fa0ce894741ed69128740e8a1ffced5b44076dc607a0d8da40945f11f692475304440766bac21ab2d9f64c40cd8723fb1cba45bfc81e20d04f60be4d72c7b6b4a1e2d35f12c18d6b91b1ece5caaf67bea98764ef74d224ede890dcc27da21638656401b728a93c21328727af16e }

condition:
	$a0
}

        