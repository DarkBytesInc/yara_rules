rule Win_Trojan_W_24
{
strings:
	$a0 = { 5768ff009affff00008d8601bd8cd28986fcbc8996febcffb6febcffb6fcbc6a019affff00008dbe00bf16579affff0000c606660001c9c3084e616a656d6e696b0856657273696f6e3108627920506177656c084d504b284329393903455845034b415403564f4c9affff00009affff00005589e5bf950b0e }

condition:
	$a0
}

        