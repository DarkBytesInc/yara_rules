rule Win_Trojan_B_256
{
strings:
	$a0 = { fc33f633ff8ed6bc007c8ede81eeedfbff0cb106add3e08ec0e80000b8eb3cab83c73c5e83ee1cb99901f3a4be4c00a5a5c744fc88018c44fefb06b97e0051cb16078bdc33c0b280e8f800ba8100b90800b8010280e280750a5052ba8000e80a005a58e8dd0072fb0653cb5053515255069ce800005d81c520012e8b4600402e8946003de803721db80300cd100e07b92300bb0400ba100ae800005d81c5d700b80013cd109d075d5a595b5851b901008bf8e88e007232509c061f8bf384d2780383c63e97f6c4017521817c1deb3c751a8bfc36807d070074478a744d8b4c4fb0019de85d00598ac159c384d27948b108e84c00722b53060e07bf3e002e89554c2e894d4ffd84d2791b57bf3d028d71c25b57b142f3a4b60041e823005faa075b9d5859c3a6b93c00f3a4bfff01578d31a4a48bd9ebe0b601b10ee80200ebb4b801039c2eff1ed701c39cf6c4f47547f6c40274420af6753e83f90175390ac074359dfb56571e52e800ff }

condition:
	$a0
}

        