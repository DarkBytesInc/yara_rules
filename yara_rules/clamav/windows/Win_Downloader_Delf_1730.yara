rule Win_Downloader_Delf_1730
{
strings:
	$a0 = { 02c8a08e01d9279ab9f87c362b3f20830c3233171b830c32c823077b0c32c8200f13176332c82083677b330103840cd726f7b7ceca7a6f1b0020313883379021404f63156550e901786bd19a19f4b468120e97e7e3649041069fabb70c228e19b38f9b03840c844246b1de58893708723c6d400500334e866aff567230 }

condition:
	$a0
}

        