rule Win_Trojan_SillyC_106
{
strings:
	$a0 = { 5b81eb0b018db71101a5a4b41a8d97de01cd218d970b01b90700b44e87ddcd21722fb000e88f00b43fb91a008d960902cd21b43ecd213e8b86f8013dbcfe770d3e8b9e0a0281c3de003bc3750db44febcdb41aba8000cd2161c3 }

condition:
	$a0
}

        
