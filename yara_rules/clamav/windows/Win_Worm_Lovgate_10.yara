rule Win_Worm_Lovgate_10
{
strings:
	$a0 = { f34bbfd3bf5ecdf172aef53bceed7f52024e6c66b0c36caa787878eed6cdb23539bb831a93cfc798e1c71bfa0e4f528c63bbef7f78f7560c41010e0a39d6b9e88e323f11470c3e0002cc7aa7747875713ddcf7e5e1fb2e457acaa1fadb4e85e86c1ff066d17c1f3c737aefbc974e2b1f16f0644b }

condition:
	$a0
}

        
