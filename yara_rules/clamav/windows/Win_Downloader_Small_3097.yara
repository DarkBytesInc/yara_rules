rule Win_Downloader_Small_3097
{
strings:
	$a0 = { c5a47257d59740cfcfad0cb09dc0b5c208f23bdda99e37b66b2467e14f8464c269ce42cb9c424d459bbe21c90dabadf7333e65c3807c004c9e9e1bcfa3f66cf33db369c34ccdc9f8707728f715ddddfc40cd5dcb106c07d56babef270bcd56c177b059d271b0832e3713f283009d53ab6deeb4e3b9440ed05aca5c6d9d0838e103aea37df68ab339dd714fc06fa4aef568f2679280ae }

condition:
	$a0
}

        