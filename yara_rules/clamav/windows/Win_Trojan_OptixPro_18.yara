rule Win_Trojan_OptixPro_18
{
strings:
	$a0 = { ee6a76a5ef7f89c047d24cb7242eb6c595ca4f32d4f82563a5a488ef2edde09ad0b3bde42112dedbdc693a05073bfa77ea1b95e3c404deee9c8daa3c54f004f5594468bc5d32dedbefb374e9164205ab9a9a08028c7d32d4cca27c9d05dd87ffe420909066fc4b3ec4156d3c96d0a34c52cd5ba8c3929a66be51c1 }

condition:
	$a0
}

        
