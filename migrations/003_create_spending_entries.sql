-- Create spending entries table (without category_id - using junction table for multi-category support)
CREATE TABLE spending_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount DECIMAL(12, 2) NOT NULL CHECK (amount > 0),
    date DATE NOT NULL,
    is_recurring BOOLEAN NOT NULL DEFAULT FALSE,
    recurrence_pattern VARCHAR(20) CHECK (recurrence_pattern IN ('daily', 'weekly', 'monthly', 'yearly')),
    currency_code VARCHAR(3) NOT NULL DEFAULT 'USD',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_currency_code CHECK (LENGTH(currency_code) = 3),
    CONSTRAINT recurrence_consistency CHECK (
        (is_recurring = FALSE AND recurrence_pattern IS NULL) OR
        (is_recurring = TRUE AND recurrence_pattern IS NOT NULL)
    )
);

-- Create indexes for efficient lookups
CREATE INDEX idx_spending_user ON spending_entries(user_id);
CREATE INDEX idx_spending_date ON spending_entries(date);
CREATE INDEX idx_spending_user_date ON spending_entries(user_id, date);
CREATE INDEX idx_spending_recurring ON spending_entries(is_recurring);
CREATE INDEX idx_spending_currency ON spending_entries(currency_code);
CREATE INDEX idx_spending_user_currency ON spending_entries(user_id, currency_code);

-- Create junction table for many-to-many relationship between spending entries and categories
CREATE TABLE spending_entry_categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spending_entry_id UUID NOT NULL REFERENCES spending_entries(id) ON DELETE CASCADE,
    category_id UUID NOT NULL REFERENCES categories(id) ON DELETE RESTRICT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_entry_category UNIQUE (spending_entry_id, category_id)
);

-- Create indexes for efficient lookups on junction table
CREATE INDEX idx_entry_categories_entry ON spending_entry_categories(spending_entry_id);
CREATE INDEX idx_entry_categories_category ON spending_entry_categories(category_id);
