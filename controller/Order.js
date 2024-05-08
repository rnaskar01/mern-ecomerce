const { Order } = require("../model/Order");
const { User } = require("../model/User");
const { sendMail, invoiceTemplate } = require("../services/common");
const { Product } = require("../model/Product");

exports.fetchOrdersByUser = async (req,res)=>{
    const { id } = req.user;
   // console.log(user);
    try {
        const orders = await Order.find({user:id});
        
       // console.log("hello"+cartItems);
        res.status(200).json(orders);
    } catch (err) {
        res.status(400).json(err);
    }
}


exports.createOrder= async (req,res)=>{
    // this product we have to get from API body 
    const order = new Order(req.body);

    for(let item of order.items){
        let product = await Product.findOne({_id:item.product.id})
        product.$inc('stock',-1*item.quantity);
        await product.save();
    }
    try{
        const doc = await order.save();
        const user = await User.findById(order.user);
        sendMail({to:user.email,html:invoiceTemplate(order),subject:'Order Received'})

        res.status(201).json(doc);
    }
    catch(err){
        res.status(400).json(err);

    }
}


exports.deleteOrder= async (req,res)=>{
    const {id} = req.params;
    try{
        const order = await Order.findByIdAndDelete(id);
        res.status(200).json(order);
    }
    catch(err){
        res.status(400).json(err);

    }
}



exports.updateOrder= async (req,res)=>{
    const {id} = req.params;
    try{
        const order = await Order.findByIdAndUpdate(id,req.body, {new: true});
        res.status(200).json(order);
    }
    catch(err){
        res.status(400).json(err);

    }
}



exports.fetchAllOrders= async (req,res)=>{

    //: we have to try with multiple categories and brand after changes in front-end
    let query = Order.find({deleted: {$ne:true}});
    let totalOrdersQuery = Order.find({deleted: {$ne:true}});


    if(req.query._sort && req.query._order){
        query =  query.sort({[req.query._sort] : req.query._order});
    }


    const totalDocs = await totalOrdersQuery.count().exec();

    if(req.query._page && req.query._limit){
        const pageSize = req.query._limit;
        const page = req.query._page
        query =  query.skip(pageSize*(page-1)).limit(pageSize);
    }

    try{
        const doc = await query.exec();
        res.set('X-Total-Count',totalDocs)
        res.status(200).json(doc);
    }
    catch(err){
        res.status(400).json(err);

    }
}