rule Win_Downloader_Swizzor_391
{
strings:
	$a0 = { 8190eb05f7b83750d33041539fe22d63768b394b43bfad5de1ebd676f5fe9f9af569de6617a2ffd9123e879b7e15bd393aa7e8832c46ff344c8a2a459edf4b474ec386eeebc1770b6ba9ab63f8cd78e6ac89f102eadb77347be8 }

condition:
	$a0
}

        
