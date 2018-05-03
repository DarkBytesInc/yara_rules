rule Win_Worm_Mytob_327
{
strings:
	$a0 = { b25b2768270d6e4ee615ffb73d570d5a15caa501425939f0df2e2533dbd5ae32afabf55bd2277ac4cf1b1a1a78c71185e2da6896c576f473c80d42edd61d43f28357ec0a4e6d1af9f5a20ce758941dad289b73e46abe243c82bcebce78550f5bee438de60d9430e6de378db6e907cfdd }

condition:
	$a0
}

        
