rule Win_Trojan_Agent_35500
{
strings:
	$a0 = { 5589e583ec08c7042401000000ff1560634300e8c8feffff908db426000000005589e583ec08c7042402000000ff1560634300e8a8feffff908db42600000000558b0d8463430089e55dffe18d742600558b0d7463430089e55dffe1909090905589e55de987370200909090909090905531d289e5568b4d088b7510538b5d0c0fb60184c0741689f68dbc27000000003a03740f420fb6040a84c075f35b89c85e5dc30fb60688040a420fb6040aebe955b91026420089e5578d55e88d8534fb }

condition:
	$a0
}

        