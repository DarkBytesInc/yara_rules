rule Win_Trojan_Hupigon_502
{
strings:
	$a0 = { 293d62a2789e32af2960563b7c75286dd72de9880c92a67220ebc7b89d0421a3b9c58ecf3255c89db7f77e8e37d634201750fc8a2a18933e05fcaf7a61e468665a4e5124cf4899c9ffc13a27e6c2ef0c7e6e669c2b80986f9064cbabb22e51186f9f17d2 }

condition:
	$a0
}

        