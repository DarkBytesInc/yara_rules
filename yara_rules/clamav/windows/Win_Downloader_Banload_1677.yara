rule Win_Downloader_Banload_1677
{
strings:
	$a0 = { 7cbcf96a80ca43e3da539b3b3f0d0dc0e5432c6d62d810f62f9e0ba84231e7f30d861e9ba6aa5b64da5dc07722d1be5b2f37fc5bf4b152d4b5a741f1d07ab34b8c51dbe0107bfc31f21edbbb3e158e617ccee053c580cf3183614ee1949db47639152731c72c3a53764363c2d35f948a4270f5cf5b9cb7c34add6b2169cdba341e2f67e25e95fce1206d6193 }

condition:
	$a0
}

        