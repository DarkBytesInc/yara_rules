rule Win_Downloader_1225_1
{
strings:
	$a0 = { 30835f41e242f882fc3b05750c8361c44400eb1fa12984a94916718802603b55fc2906421c0eb2683393eb53ac75eac2acc6c5fc8bc7a5f06702082a0771d800fc0d30b85b3d817b4702eed37d2a680004cd4bc6438b036560f50a2c1ff38bc88bd4e0abe91d10bd01590a8b5327cbc4d2579908cbecfff053 }

condition:
	$a0
}

        