-- V31: Fix display_order to be 0-indexed for JPA @OrderColumn compatibility
-- @OrderColumn is 0-based; V30 inserted 1-based values causing null entries in Hibernate lists

UPDATE auth_flow_step_methods
SET display_order = display_order - 1
WHERE display_order > 0
  AND step_id IN (
    SELECT step_id
    FROM auth_flow_step_methods
    GROUP BY step_id
    HAVING MIN(display_order) > 0
  );
