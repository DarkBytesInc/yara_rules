rule Win_Trojan_SdBot_3887
{
strings:
	$a0 = { 7f338ab273109a7c649656a5744d94d546dd8347003bfb16270f5aa80fa8b818278ee04aa80e2da36b1b544be4ad37501bfa1fc8bab13c724f3d2009cbd3d8272172f87e479517304a8e46cdbd5de6ea83cb9e4a3be6ef0ab3565ecd }

condition:
	$a0
}

        
