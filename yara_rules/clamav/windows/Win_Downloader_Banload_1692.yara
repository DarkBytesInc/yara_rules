rule Win_Downloader_Banload_1692
{
strings:
	$a0 = { 713631a12d3de5bae831b830f65895b9910833bea443fdaf2085e71801d3031b84c25cc9566104e393d6f29ae656b3da3fc045988594003a7ab4c0333023697d7c293e01e03a562d31b7277b482356aec3376f2e99e444d73dd046783103d9b6af4a305bb875cd66d214a891945942314f63a5aa0ad098cddfff7ae290005e0000800000002ca70be04cbba25d752e50b2d998d76b5c }

condition:
	$a0
}

        