rule Win_Spyware_Banker_3466
{
strings:
	$a0 = { eefaec3d2c2d116d4c9d2ce3679de659e039cea5a49abd3fb087ab6bd2e3206cd2b85aee6279cb811a25ad3e77a9d1db6f25922d1c74c1a058332d7f7f13bef45141481793dea5d14959b2d94003dfdcfc7dbf1fcaeee5e4767fc700d4809b }

condition:
	$a0
}

        
