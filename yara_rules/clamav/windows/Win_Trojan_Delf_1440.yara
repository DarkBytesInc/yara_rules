rule Win_Trojan_Delf_1440
{
strings:
	$a0 = { 4082f54d4b54a0f6731d1dc903625e83db997aaf9a9de32df2d054678f6c2bc1f18b1943a2fa7194b31862187da3c53419ab5cd145f34e1444a42b9528f37e5fb83cdadc777d1be35c6e81cc2ba39f9dbde716a32c47efd00a5fad06bdd54269c377b80bb0783c9f56a28dbd7acecd163efeaa125f86acdb2538129794bfbf599cb766845dc212988adf76ce940ce1c27fbc66d0dae1 }

condition:
	$a0
}

        