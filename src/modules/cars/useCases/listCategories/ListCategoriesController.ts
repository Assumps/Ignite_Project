import { Request, Response } from "express";
import { ListCategoriesUseCase } from "./ListCategoriesUseCase";

class ListCategoriesController {

    constructor(private ListCategoriesUseCase: ListCategoriesUseCase){

    }

    handle(Request: Request, response: Response){
        const all = this.ListCategoriesUseCase.execute();

        return response.json(all)
    }
}

export { ListCategoriesController }