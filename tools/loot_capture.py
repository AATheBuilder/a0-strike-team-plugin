from helpers.tool import Tool, Response
from helpers.recon_memory import persist_loot
from helpers.secrets import get_secrets_manager

class LootCapture(Tool):
    """
    Capture harvested credentials, keys, or sensitive data (loot) 
    and store it in the structured recon memory.
    """

    async def execute(self, target: str, kind: str, value: str, username: str = "", context: str = "", **kwargs) -> Response:
        if not target or not kind or not value:
            return Response(message="Error: 'target', 'kind', and 'value' are required.", break_loop=False)

        try:
            # Handle secrets through the manager wrapper for masking and protection
            secrets_mgr = get_secrets_manager(self.agent.context)
            
            # Persist loot (now encrypted in recon memory)
            loot = persist_loot(
                target=target,
                kind=kind,
                value=value,
                username=username,
                context=context
            )
            
            # Mask the secret in the response message
            masked_value = secrets_mgr.mask_values(value)
            
            msg = f"Successfully captured loot ({kind}) for target {target}.\n"
            msg += f"Value: {masked_value}\n"
            msg += f"Entity ID: {loot['id']}\n"
            
            if value == masked_value and "§§secret" not in value:
                msg += "\n[SECURITY TIP] This value was captured as plaintext. Consider adding it to your secrets store and using a §§secret(KEY) placeholder next time to reduce exposure risk."
            
            return Response(message=msg, break_loop=False)
        except Exception as e:
            return Response(message=f"Error capturing loot: {str(e)}", break_loop=False)
