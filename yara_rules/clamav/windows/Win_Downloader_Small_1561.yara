rule Win_Downloader_Small_1561
{
strings:
	$a0 = { 47580576b3a160ed451e66ab6a4cd2847287290f00de92c36b9bc9afa6c60dcb48555df45cf35e67b964c5e4d728dd255bfe6413298b8237abb20264996f18fde6c2e3537ab37510053a83f1dee8c5c15963106e596bb3087739f72cd981594c0e107d3d0ac3f2c8835c44bc059461c404c71548183939183db058c41f53554722775b9e3b0e2605de5ff6b9e64b0c753f2595ed8dda }

condition:
	$a0
}

        