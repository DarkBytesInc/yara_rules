rule Win_Spyware_Banker_1137
{
strings:
	$a0 = { dcab2dba0ccb2f88e1f64a523581063dbdce301de7ad091f17b0bfab495f0d674b86bcd0c3f92f04f572eea6363091c072dd25bbb3472ab06785df95bd72df1605fd4957851ec595a328124d6c13615ce5fab9e43ef74d8fef1a }

condition:
	$a0
}

        
