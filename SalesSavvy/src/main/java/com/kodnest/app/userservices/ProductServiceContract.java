package com.kodnest.app.userservices;

import java.util.List;

import com.kodnest.app.entities.Product;

public interface ProductServiceContract {

	 public List<Product> getProductsByCategory(String categoryName);
	 public List<String> getProductImages(Integer productId);
}
