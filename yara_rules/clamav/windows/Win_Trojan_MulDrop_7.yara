rule Win_Trojan_MulDrop_7
{
strings:
	$a0 = { 6c696e65205365727669631a534f4654574152ffedb7ed455c4d0d72306f66745c571f646f77735c437572f6db7ffb72656e74562973696f6e5c52756e74436f6d707572dbeddbff72207761732073756341737366755679203466b6fdeddb65631964230d0a6f616c6f67662e1269e75936cdff465245454d5a }

condition:
	$a0
}

        