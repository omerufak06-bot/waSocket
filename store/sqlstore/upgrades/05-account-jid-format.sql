-- v5: Update account JID format
UPDATE waSocket_device SET jid=REPLACE(jid, '.0', '');
