rule Win_Spyware_493_2
{
strings:
	$a0 = { 65b959eecaaedc94f7afaeee65aee4adcbaeaef900625111b09124a8cae4edefcaaeb90b0651514efc92049ad9d295e163063b14dda391eeca398f7f2142391e604642f9b695aeee3e912514dd1baeeeca399d7f2142391e6046 }

condition:
	$a0
}

        
