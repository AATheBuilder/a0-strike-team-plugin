from helpers.tool import Tool, Response
from helpers.recon_memory import persist_loot

class LootCapture(Tool):
    """
    Capture harvested credentials, keys, or sensitive data (loot) 
    and store it in the structured recon memory.
    """

    async def execute(self, target: str, kind: str, value: str, username: str = "", context: str = "", **kwargs) -> Response:
        if not target or not kind or not value:
            return Response(message="Error: 'target', 'kind', and 'value' are required.", break_loop=False)

        try:
            loot = persist_loot(
                target=target,
                kind=kind,
                value=value,
                username=username,
                context=context
            )
            
            msg = f"Successfully captured loot: {loot['value']} for target {target}.\n"
            msg += f"Entity ID: {loot['id']}"
            
            return Response(message=msg, break_loop=False)
        except Exception as e:
            return Response(message=f"Error capturing loot: {str(e)}", break_loop=False)
