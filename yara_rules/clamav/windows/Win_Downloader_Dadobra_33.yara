rule Win_Downloader_Dadobra_33
{
strings:
	$a0 = { 61436cee7ba66595976d0d91686eecc1dc6400101b28072c09d0dd7db16c376f251f29000ead621779888daf72891f457f636363dd3f1d63797347767d6cbaef2d7329870b0564017263936dc9295d70a36d8b758c75a77bfd8b27052e2573c118c2266f4103a7c669c68c039f7db191674126638d03076cc3085319431981763392f060baa3646f6995945d16fb937009e9163378ee }

condition:
	$a0
}

        