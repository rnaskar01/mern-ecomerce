const {Product} = require ("../model/Product")


exports.createProduct= async (req,res)=>{
    // this product we have to get from API body 
    const product = new Product(req.body);
    product.discountPrice = Math.round(product.price*(1-product.discountPercentage/100))
  //console.log("its work"+product);
    try{
        //console.log("its working");
        const doc = await product.save();
        res.status(201).json(doc);
    }
    catch(err){
       // console.log(err);
        res.status(400).json(err);

    }
}


exports.fetchAllProducts= async (req,res)=>{

    //: we have to try with multiple categories and brand after changes in front-end
    let condition = {}
    if(!req.query.admin){
        condition.deleted = {$ne:true}
    }
    let query = Product.find(condition);
    let totalProductQuery = Product.find(condition);
   // console.log(req.query.category);
    if(req.query.category){
        query =  query.find({category: {$in:req.query.category.split(',')}});
        totalProductQuery =  totalProductQuery.find({category: {$in:req.query.category.split(',')}});

    }

    if(req.query.brand){
        query = query.find({brand: {$in:req.query.brand.split(',')}});
        totalProductQuery = totalProductQuery.find({brand: {$in:req.query.brand.split(',')}});
    }

    if(req.query._sort && req.query._order){
        query =  query.sort({[req.query._sort] : req.query._order});
    }


    const totalDocs = await totalProductQuery.count().exec();

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


exports.fetchProductById= async (req,res)=>{
    const {id} = req.params;
    try{
        const product = await Product.findById(id);
        res.status(200).json(product);
    }
    catch(err){
        res.status(400).json(err);

    }
}


exports.updateProduct= async (req,res)=>{
    const {id} = req.params;
    try{
        const product = await Product.findByIdAndUpdate(id,req.body, {new: true});
        product.discountPrice = Math.round(product.price*(1-product.discountPercentage/100))
        const updateProduct = await product.save();
        res.status(200).json(updateProduct);
    }
    catch(err){
        res.status(400).json(err);

    }
}