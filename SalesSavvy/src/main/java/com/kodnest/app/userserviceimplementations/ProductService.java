package com.kodnest.app.userserviceimplementations;



import org.springframework.stereotype.Service;

import com.kodnest.app.entities.Category;
import com.kodnest.app.entities.Product;
import com.kodnest.app.entities.ProductImage;
import com.kodnest.app.userrepositories.CategoryRepository;
import com.kodnest.app.userrepositories.ProductImageRepository;
import com.kodnest.app.userrepositories.ProductRepository;
import com.kodnest.app.userservices.ProductServiceContract;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
@Service
public class ProductService implements ProductServiceContract {

   
    private ProductRepository productRepository;
    private ProductImageRepository productImageRepository;
    private CategoryRepository categoryRepository;
    
    public ProductService(ProductRepository productRepository, ProductImageRepository productImageRepository,
			CategoryRepository categoryRepository) {
		super();
		this.productRepository = productRepository;
		this.productImageRepository = productImageRepository;
		this.categoryRepository = categoryRepository;
	}

	@Override
    public List<Product> getProductsByCategory(String categoryName) {
        if (categoryName != null && !categoryName.isEmpty()) {
            Optional<Category> categoryOpt = categoryRepository.findByCategoryName(categoryName);
            if (categoryOpt.isPresent()) {
                Category category = categoryOpt.get();
                return productRepository.findByCategory_CategoryId(category.getCategoryId());
            } else {
                throw new RuntimeException("Category not found");
            }
        } else {
            return productRepository.findAll();
        }
    }

    @Override
    public List<String> getProductImages(Integer productId) {
        List<ProductImage> productImages =
                productImageRepository.findByProduct_ProductId(productId);

        List<String> imageUrls = new ArrayList<>();
        for (ProductImage image : productImages) {
            imageUrls.add(image.getImageUrl());
        }
        return imageUrls;
    }
}
