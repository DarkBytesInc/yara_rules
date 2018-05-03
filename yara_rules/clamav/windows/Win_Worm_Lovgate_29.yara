rule Win_Worm_Lovgate_29
{
strings:
	$a0 = { e99db50db6ac1fcfcd303268c8ac17cd501a2dd63247cee319658384e86cecee4fbf517565687f8866cafaa89e4a615d2e80 }

condition:
	$a0
}

        
