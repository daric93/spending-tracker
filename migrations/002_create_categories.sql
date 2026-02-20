-- Create categories table
CREATE TABLE categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL,
    category_type VARCHAR(20) NOT NULL CHECK (category_type IN ('predefined', 'custom')),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_category_per_user UNIQUE (name, user_id),
    CONSTRAINT predefined_no_user CHECK (
        (category_type = 'predefined' AND user_id IS NULL) OR
        (category_type = 'custom' AND user_id IS NOT NULL)
    )
);

-- Create indexes for efficient lookups
CREATE INDEX idx_categories_user ON categories(user_id);
CREATE INDEX idx_categories_name ON categories(name);

-- Insert predefined categories
INSERT INTO categories (name, category_type, user_id) VALUES
    ('groceries', 'predefined', NULL),
    ('restaurant', 'predefined', NULL),
    ('travel', 'predefined', NULL),
    ('transportation', 'predefined', NULL),
    ('entertainment', 'predefined', NULL),
    ('utilities', 'predefined', NULL),
    ('healthcare', 'predefined', NULL),
    ('shopping', 'predefined', NULL),
    ('education', 'predefined', NULL),
    ('personal_care', 'predefined', NULL),
    ('housing', 'predefined', NULL),
    ('debt_payment', 'predefined', NULL),
    ('savings', 'predefined', NULL),
    ('clothing', 'predefined', NULL),
    ('household_supplies', 'predefined', NULL),
    ('insurance', 'predefined', NULL),
    ('kids', 'predefined', NULL)
ON CONFLICT (name, user_id) DO NOTHING;
