rule Win_Spyware_Banker_2928
{
strings:
	$a0 = { 02fd7631a0d0895ce03cbd0b8e358ff980eb1be2a0c8567edfed9e2cdf703afeed55853e3aa9c2ca49e3f7bd259362df14cf5a519a89a1e63e32902a764b6f9c7b2edbe5aa63f6dd04df391e6a0e389ffbc87e39293fdfc6e09aee8236ba62e054df8cf50508fd57cdfb028f2ec4 }

condition:
	$a0
}

        
