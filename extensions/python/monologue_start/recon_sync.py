from helpers.recon_memory import load_recon_memory

async def execute(agent, **kwargs):
    """
    Hunter Recon Sync: Injects the latest reconnaissance summary into the agent's
    monologue context, ensuring the attack surface status is always visible.
    """
    
    # Only run for the Hacker or specialized Red Team profiles
    active_profile = agent.profile_name.lower()
    if "hacker" not in active_profile and "recon" not in active_profile and "exploit" not in active_profile:
         return

    try:
        data = load_recon_memory()
        entities = data.get("entities", [])
        
        # Simple stats for the prompt
        counts = {}
        for entity in entities:
            etype = entity.get("entity_type")
            counts[etype] = counts.get(etype, 0) + 1
            
        summary = "\n[HUNTER: RECON SURFACE STATUS]\n"
        if counts:
             summary += "Active Recon Surface contains:\n"
             for etype, count in counts.items():
                 summary += f"- {etype}: {count}\n"
             summary += "Use 'recon_memory_query' to fetch tactical details."
        else:
             summary += "No active recon surface mapped yet. Start with 'gather_surface_report'."
             
        # Inject into the next prompt
        agent.hist_add_warning(summary)
        
    except Exception:
        pass # Silent fail to prevent monologue disruption
