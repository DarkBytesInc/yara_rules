rule Win_Trojan_Agent_32663
{
strings:
	$a0 = { 7e0497d2c089102f639c28d65caeec29bed23a6fe4102310f630387dcbede4295eabc62b70267658d94f32f4afb93cadddf489f86e59a439a40568313f781aac23289e4f558cae60a14a9abb79a5c7cc8180350da30d934c41e54bb59bd1f5084527f089fdf2bc688633bd40af631d50366d770ebb824ab36b2cb032697da1582eb59288311dae48ace78c40 }

condition:
	$a0
}

        