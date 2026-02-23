use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::models::category::{Category, CategoryType, PREDEFINED_CATEGORIES};
use crate::repositories::category_repository::{CategoryRepository, RepositoryError};

/// Category service errors
#[derive(Debug, thiserror::Error)]
pub enum CategoryError {
    #[error("Category with this name already exists")]
    DuplicateName,

    #[error("Category not found")]
    CategoryNotFound,

    #[error("Category is in use and cannot be deleted")]
    CategoryInUse,

    #[error("Cannot modify predefined categories")]
    CannotModifyPredefined,

    #[error("Unauthorized to access this category")]
    Unauthorized,

    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// Result of a category rename operation
#[derive(Debug)]
pub enum RenameResult {
    Success(Category),
    ConflictDetected { existing_category: Category },
}

/// Trait defining category service operations
#[async_trait]
pub trait CategoryService: Send + Sync {
    /// Get all categories available to a user (predefined + user's custom categories)
    async fn get_categories(&self, user_id: Uuid) -> Result<Vec<Category>, CategoryError>;

    /// Get or create a category by name (auto-creates custom category if not found)
    async fn get_or_create_by_name(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Category, CategoryError>;
}

/// Implementation of CategoryService
pub struct CategoryServiceImpl {
    category_repository: Arc<dyn CategoryRepository>,
}

impl CategoryServiceImpl {
    pub fn new(category_repository: Arc<dyn CategoryRepository>) -> Self {
        Self {
            category_repository,
        }
    }
}

#[async_trait]
impl CategoryService for CategoryServiceImpl {
    async fn get_categories(&self, user_id: Uuid) -> Result<Vec<Category>, CategoryError> {
        self.category_repository
            .find_by_user(user_id)
            .await
            .map_err(|e| match e {
                RepositoryError::NotFound => CategoryError::CategoryNotFound,
                RepositoryError::DatabaseError(msg) => CategoryError::DatabaseError(msg),
                RepositoryError::ConstraintViolation(msg) => CategoryError::DatabaseError(msg),
            })
    }

    async fn get_or_create_by_name(
        &self,
        user_id: Uuid,
        name: &str,
    ) -> Result<Category, CategoryError> {
        // First, check if it's a predefined category
        if PREDEFINED_CATEGORIES.contains(&name) {
            // Look for predefined category (user_id = None)
            if let Some(category) = self
                .category_repository
                .find_by_name(None, name)
                .await
                .map_err(|e| CategoryError::DatabaseError(e.to_string()))?
            {
                return Ok(category);
            }
        }

        // Check if user already has a custom category with this name
        if let Some(category) = self
            .category_repository
            .find_by_name(Some(user_id), name)
            .await
            .map_err(|e| CategoryError::DatabaseError(e.to_string()))?
        {
            return Ok(category);
        }

        // Create new custom category for the user
        let new_category = Category {
            id: Uuid::new_v4(),
            name: name.to_string(),
            category_type: CategoryType::Custom,
            user_id: Some(user_id),
            created_at: chrono::Utc::now(),
        };

        self.category_repository
            .create(new_category)
            .await
            .map_err(|e| match e {
                RepositoryError::ConstraintViolation(_) => CategoryError::DuplicateName,
                RepositoryError::DatabaseError(msg) => CategoryError::DatabaseError(msg),
                RepositoryError::NotFound => {
                    CategoryError::DatabaseError("Unexpected error".to_string())
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Mock CategoryRepository for testing
    struct MockCategoryRepository {
        categories: Mutex<HashMap<(Option<Uuid>, String), Category>>,
        should_fail: bool,
    }

    impl MockCategoryRepository {
        fn new() -> Self {
            let mut categories = HashMap::new();

            // Add predefined categories
            for &name in PREDEFINED_CATEGORIES.iter() {
                let category = Category {
                    id: Uuid::new_v4(),
                    name: name.to_string(),
                    category_type: CategoryType::Predefined,
                    user_id: None,
                    created_at: Utc::now(),
                };
                categories.insert((None, name.to_string()), category);
            }

            Self {
                categories: Mutex::new(categories),
                should_fail: false,
            }
        }

        fn with_failure() -> Self {
            Self {
                categories: Mutex::new(HashMap::new()),
                should_fail: true,
            }
        }
    }

    #[async_trait]
    impl CategoryRepository for MockCategoryRepository {
        async fn create(&self, category: Category) -> Result<Category, RepositoryError> {
            if self.should_fail {
                return Err(RepositoryError::DatabaseError("Database error".to_string()));
            }

            let mut categories = self.categories.lock().unwrap();
            let key = (category.user_id, category.name.clone());

            if categories.contains_key(&key) {
                return Err(RepositoryError::ConstraintViolation(
                    "Category already exists".to_string(),
                ));
            }

            categories.insert(key, category.clone());
            Ok(category)
        }

        async fn find_by_id(&self, id: Uuid) -> Result<Option<Category>, RepositoryError> {
            let categories = self.categories.lock().unwrap();
            Ok(categories.values().find(|c| c.id == id).cloned())
        }

        async fn find_by_name(
            &self,
            user_id: Option<Uuid>,
            name: &str,
        ) -> Result<Option<Category>, RepositoryError> {
            if self.should_fail {
                return Err(RepositoryError::DatabaseError("Database error".to_string()));
            }

            let categories = self.categories.lock().unwrap();
            Ok(categories.get(&(user_id, name.to_string())).cloned())
        }

        async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Category>, RepositoryError> {
            if self.should_fail {
                return Err(RepositoryError::DatabaseError("Database error".to_string()));
            }

            let categories = self.categories.lock().unwrap();
            let mut result: Vec<Category> = categories
                .values()
                .filter(|c| c.user_id.is_none() || c.user_id == Some(user_id))
                .cloned()
                .collect();
            result.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(result)
        }
    }

    #[tokio::test]
    async fn test_get_categories_returns_predefined_and_custom() {
        let repo = Arc::new(MockCategoryRepository::new());
        let service = CategoryServiceImpl::new(repo.clone());

        let user_id = Uuid::new_v4();

        // Add a custom category for the user
        let custom_category = Category {
            id: Uuid::new_v4(),
            name: "my_custom_category".to_string(),
            category_type: CategoryType::Custom,
            user_id: Some(user_id),
            created_at: Utc::now(),
        };
        repo.create(custom_category.clone()).await.unwrap();

        let result = service.get_categories(user_id).await;
        assert!(result.is_ok());

        let categories = result.unwrap();
        // Should have all predefined categories + 1 custom
        assert_eq!(categories.len(), PREDEFINED_CATEGORIES.len() + 1);

        // Verify predefined categories are included
        assert!(categories.iter().any(|c| c.name == "groceries"));
        assert!(categories.iter().any(|c| c.name == "restaurant"));

        // Verify custom category is included
        assert!(
            categories
                .iter()
                .any(|c| c.name == "my_custom_category" && c.user_id == Some(user_id))
        );
    }

    #[tokio::test]
    async fn test_get_categories_database_error() {
        let repo = Arc::new(MockCategoryRepository::with_failure());
        let service = CategoryServiceImpl::new(repo);

        let user_id = Uuid::new_v4();
        let result = service.get_categories(user_id).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CategoryError::DatabaseError(_)
        ));
    }

    #[tokio::test]
    async fn test_get_or_create_by_name_returns_predefined_category() {
        let repo = Arc::new(MockCategoryRepository::new());
        let service = CategoryServiceImpl::new(repo);

        let user_id = Uuid::new_v4();
        let result = service.get_or_create_by_name(user_id, "groceries").await;

        assert!(result.is_ok());
        let category = result.unwrap();
        assert_eq!(category.name, "groceries");
        assert_eq!(category.category_type, CategoryType::Predefined);
        assert!(category.user_id.is_none());
    }

    #[tokio::test]
    async fn test_get_or_create_by_name_returns_existing_custom_category() {
        let repo = Arc::new(MockCategoryRepository::new());
        let service = CategoryServiceImpl::new(repo.clone());

        let user_id = Uuid::new_v4();

        // Create a custom category first
        let custom_category = Category {
            id: Uuid::new_v4(),
            name: "my_category".to_string(),
            category_type: CategoryType::Custom,
            user_id: Some(user_id),
            created_at: Utc::now(),
        };
        repo.create(custom_category.clone()).await.unwrap();

        // Now try to get or create it again
        let result = service.get_or_create_by_name(user_id, "my_category").await;

        assert!(result.is_ok());
        let category = result.unwrap();
        assert_eq!(category.name, "my_category");
        assert_eq!(category.id, custom_category.id); // Should be the same category
    }

    #[tokio::test]
    async fn test_get_or_create_by_name_creates_new_custom_category() {
        let repo = Arc::new(MockCategoryRepository::new());
        let service = CategoryServiceImpl::new(repo);

        let user_id = Uuid::new_v4();
        let result = service
            .get_or_create_by_name(user_id, "new_custom_category")
            .await;

        assert!(result.is_ok());
        let category = result.unwrap();
        assert_eq!(category.name, "new_custom_category");
        assert_eq!(category.category_type, CategoryType::Custom);
        assert_eq!(category.user_id, Some(user_id));
    }

    #[tokio::test]
    async fn test_get_or_create_by_name_database_error() {
        let repo = Arc::new(MockCategoryRepository::with_failure());
        let service = CategoryServiceImpl::new(repo);

        let user_id = Uuid::new_v4();
        let result = service.get_or_create_by_name(user_id, "new_category").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CategoryError::DatabaseError(_)
        ));
    }

    #[tokio::test]
    async fn test_get_or_create_by_name_different_users_can_have_same_custom_category_name() {
        let repo = Arc::new(MockCategoryRepository::new());
        let service = CategoryServiceImpl::new(repo);

        let user1_id = Uuid::new_v4();
        let user2_id = Uuid::new_v4();

        // User 1 creates a custom category
        let result1 = service.get_or_create_by_name(user1_id, "my_category").await;
        assert!(result1.is_ok());
        let category1 = result1.unwrap();

        // User 2 creates a custom category with the same name
        let result2 = service.get_or_create_by_name(user2_id, "my_category").await;
        assert!(result2.is_ok());
        let category2 = result2.unwrap();

        // They should be different categories
        assert_ne!(category1.id, category2.id);
        assert_eq!(category1.user_id, Some(user1_id));
        assert_eq!(category2.user_id, Some(user2_id));
    }

    #[tokio::test]
    async fn test_predefined_categories_constant() {
        // Verify the predefined categories constant has the expected values
        assert_eq!(PREDEFINED_CATEGORIES.len(), 17);
        assert!(PREDEFINED_CATEGORIES.contains(&"groceries"));
        assert!(PREDEFINED_CATEGORIES.contains(&"restaurant"));
        assert!(PREDEFINED_CATEGORIES.contains(&"travel"));
        assert!(PREDEFINED_CATEGORIES.contains(&"transportation"));
        assert!(PREDEFINED_CATEGORIES.contains(&"entertainment"));
        assert!(PREDEFINED_CATEGORIES.contains(&"utilities"));
        assert!(PREDEFINED_CATEGORIES.contains(&"healthcare"));
        assert!(PREDEFINED_CATEGORIES.contains(&"shopping"));
        assert!(PREDEFINED_CATEGORIES.contains(&"education"));
        assert!(PREDEFINED_CATEGORIES.contains(&"personal_care"));
        assert!(PREDEFINED_CATEGORIES.contains(&"housing"));
        assert!(PREDEFINED_CATEGORIES.contains(&"debt_payment"));
        assert!(PREDEFINED_CATEGORIES.contains(&"savings"));
        assert!(PREDEFINED_CATEGORIES.contains(&"clothing"));
        assert!(PREDEFINED_CATEGORIES.contains(&"household_supplies"));
        assert!(PREDEFINED_CATEGORIES.contains(&"insurance"));
        assert!(PREDEFINED_CATEGORIES.contains(&"kids"));
    }
}
