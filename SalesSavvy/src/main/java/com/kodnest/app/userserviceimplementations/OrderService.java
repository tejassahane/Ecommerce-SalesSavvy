package com.kodnest.app.userserviceimplementations;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.kodnest.app.entities.OrderItem;
import com.kodnest.app.entities.Product;
import com.kodnest.app.entities.ProductImage;
import com.kodnest.app.entities.User;
import com.kodnest.app.userrepositories.OrderItemRepository;
import com.kodnest.app.userrepositories.ProductImageRepository;
import com.kodnest.app.userrepositories.ProductRepository;
import com.kodnest.app.userservices.OrderServiceContract;

@Service
public class OrderService implements OrderServiceContract{


	
	private OrderItemRepository orderItemRepository;

   
    private ProductRepository productRepository;

    
    private ProductImageRepository productImageRepository;


	public OrderService(OrderItemRepository orderItemRepository, ProductRepository productRepository,
			ProductImageRepository productImageRepository) {
		super();
		this.orderItemRepository = orderItemRepository;
		this.productRepository = productRepository;
		this.productImageRepository = productImageRepository;
	}


	@Override
	public Map<String, Object> getOrdersForUser(User user) {
		List<OrderItem> orderItems = orderItemRepository.findSuccessfulOrderItemsByUserId(user.getUserId());

		Map<String, Object> response = new HashMap<>();
        response.put("username", user.getUsername());
        response.put("role", user.getRole());
		
		 List<Map<String, Object>> products = new ArrayList<>();
	        
		 for (OrderItem item : orderItems) {
	            Product product = productRepository.findById(item.getProductId()).orElse(null);
	            if (product == null) {
	                continue; // Skip if the product does not exist
	            }

	            // Fetch the product image (if available)
	            List<ProductImage> images = productImageRepository.findByProduct_ProductId(product.getProductId());
	            String imageUrl = images.isEmpty() ? null : images.get(0).getImageUrl();

	            // Create a product details map
	            Map<String, Object> productDetails = new HashMap<>();
	            productDetails.put("order_id", item.getOrder().getOrderId());
	            productDetails.put("quantity", item.getQuantity());
	            productDetails.put("total_price", item.getTotalPrice());
	            productDetails.put("image_url", imageUrl);
	            productDetails.put("product_id", product.getProductId());
	            productDetails.put("name", product.getName());
	            productDetails.put("description", product.getDescription());
	            productDetails.put("price_per_unit", item.getPricePerUnit());

	            products.add(productDetails);
	        }

	        // Add the products list to the response
	        response.put("products", products);

	        return response;
	}
    
}
