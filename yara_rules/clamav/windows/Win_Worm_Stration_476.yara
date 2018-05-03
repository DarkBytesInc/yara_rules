rule Win_Worm_Stration_476
{
strings:
	$a0 = { 52c4cbd42bd7554217a5c7ce681e51d31fcbad23cc4a3c692ee2e6f8ca4848fba28444a5bcc3ae5e78340f5ec80844d4dd7a406a18656de37d9f21082a155706ea5dfd506740936ac8ef201158729bcf89ed4bdd72a07c0ebd18255ddfca255e6a59980b0a1f4aa89bd6b1 }

condition:
	$a0
}

        
