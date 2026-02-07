package com.kodnest.app.userservices;

import java.math.BigDecimal;
import java.util.List;

import com.kodnest.app.entities.OrderItem;
import com.razorpay.RazorpayException;

public interface PaymentServiceContract {
	 public String createOrder(int userId, BigDecimal totalAmount, List<OrderItem> cartItems) throws RazorpayException;
	 public boolean verifyPayment(String razorpayOrderId, String razorpayPaymentId, String razorpaySignature, int userId);
}
