rule Win_Trojan_Gaobot_11
{
strings:
	$a0 = { 5a6f43caf8ac1b8318112c94e7c35ad861439597718c60bbbd21666c53594ea53fafb68d41c7f15755446d6897905052af6e4902b18d6d47d08f6529cc8e5026 }

condition:
	$a0
}

        
