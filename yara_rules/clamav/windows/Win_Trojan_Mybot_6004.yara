rule Win_Trojan_Mybot_6004
{
strings:
	$a0 = { 05573b27802b9dba9caed0d24562dd48fe105f96f5c11391275485ed15f32132b53a290fd4733524d78fa7f5b77d7f83af880ab9a496b5c519f7c6c94edb7d46d82ee3b6d0e15202ca3f42c5f49278163bb04795db97b3e86cb175649d7881221e0f9f73efcaabfc934bc294b4ea209507a3ac8466990cde53fc8f02ccc79ac8275a9e0adffdc049770d740e }

condition:
	$a0
}

        