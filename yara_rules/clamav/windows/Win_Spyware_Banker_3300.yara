rule Win_Spyware_Banker_3300
{
strings:
	$a0 = { a558470f29a63b8a1da603a8f47c1a70218525270a3fcf09b953719f960c534dca3ff8e548a39a9b32c24ec05ca885dcf4a9580b3ca53e6c229431d5f590e04d4623f2bfa536a16deff2837bad704e97422b5b83611d6e099d3bbffcecf89dad91df1993f40dd53d71d6253d73bdcb125379eeb31236eeaef7edbc7e755215fda270e0e3cdf26922f50c02df }

condition:
	$a0
}

        