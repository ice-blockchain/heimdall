-- SPDX-License-Identifier: ice License 1.0

CREATE OR REPLACE FUNCTION extract_swap_calldata_from_custom_handleops(tx_input TEXT)
    RETURNS TEXT AS $$
DECLARE
    hex_clean TEXT;
    function_selector TEXT;
    swap_4param_selector TEXT := '83362e17';
    swap_5param_selector TEXT := '027c101d';
    handleops_selector TEXT := '74fa4121';
    metamask_execute_selector TEXT := 'e9ae5c53';
    swap_position INT;
BEGIN
    IF tx_input IS NULL OR length(tx_input) < 10 THEN
        RETURN tx_input;
    END IF;

    hex_clean := REPLACE(tx_input, '0x', '');
    function_selector := substring(hex_clean from 1 for 8);

    IF function_selector != handleops_selector AND function_selector != metamask_execute_selector THEN
        RETURN tx_input;
    END IF;

    -- Search for 4-param swap selector
    swap_position := position(swap_4param_selector in hex_clean);
    IF swap_position > 0 THEN
        RETURN '0x' || substring(hex_clean from swap_position);
    END IF;

    -- Search for 5-param swap selector
    swap_position := position(swap_5param_selector in hex_clean);
    IF swap_position > 0 THEN
        RETURN '0x' || substring(hex_clean from swap_position);
    END IF;

    RETURN tx_input;
EXCEPTION
    WHEN OTHERS THEN
        RETURN tx_input;
END;
$$ LANGUAGE plpgsql IMMUTABLE;