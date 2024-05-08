const { Cart } = require("../model/Cart");

exports.fetchCartByUser = async (req,res)=>{
    const {id} = req.user;
   // console.log(user);
    try {
        const cartItems = await Cart.find({user:id}).populate('product');
        
       //console.log("hello"+cartItems);
        res.status(200).json(cartItems);
    } catch (err) {
       // console.log(err);
        res.status(400).json(err);
    }
}


exports.addToCart= async (req,res)=>{
    // this product we have to get from API body 
    const {id} = req.user;
    const cart = new Cart({...req.body,user:id});
    //console.log("its work"+cart);
    try{
        const doc = await cart.save();
        const result = await doc.populate('product')
        res.status(201).json(result);
    }
    catch(err){
       // console.log(err);
        res.status(400).json(err);

    }
}


exports.deleteFromCart= async (req,res)=>{
    const {id} = req.params;
    try{
        const doc = await Cart.findByIdAndDelete(id);
        res.status(200).json(doc);
    }
    catch(err){
        res.status(400).json(err);

    }
}



exports.updateCart= async (req,res)=>{
    const {id} = req.params;
    try{
        const cart = await Cart.findByIdAndUpdate(id,req.body, {new: true});
        const result = await cart.populate('product')
        res.status(200).json(result);
    }
    catch(err){
        res.status(400).json(err);

    }
}